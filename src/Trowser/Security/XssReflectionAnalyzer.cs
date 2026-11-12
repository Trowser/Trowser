using System.Text.RegularExpressions;
using System.Web;

namespace Trowser.Security;

/// <summary>
/// Context-aware analysis of reflected payloads in HTTP response bodies.
/// Distinguishes safe text-node reflection from dangerous attribute/script contexts.
/// </summary>
public static class XssReflectionAnalyzer
{
    private static readonly Regex EventHandlerAttr = new(@"\bon\w+\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UrlAttr = new(@"\b(href|src|action|formaction|xlink:href)\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HtmlMarkup = new(@"<[^>]+>|on\w+\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex AlertCall = new(@"alert\s*\([^)]*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex EventHandlerName = new(@"on\w+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed record ReflectionAnalysis(
        string Context,
        bool Encoded,
        bool Dangerous,
        string? Reason,
        string Surrounding);

    public static bool IsJavascriptUriPayload(string payload) =>
        payload.TrimStart().StartsWith("javascript:", StringComparison.OrdinalIgnoreCase);

    public static bool IsDataUriPayload(string payload) =>
        payload.TrimStart().StartsWith("data:", StringComparison.OrdinalIgnoreCase);

    public static bool ContainsHtmlMarkup(string payload) => HtmlMarkup.IsMatch(payload);

    public static string DetermineReflectionContext(string body, string payload, string? contentType)
    {
        if (!string.IsNullOrWhiteSpace(contentType))
        {
            if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
                return "json";
            if (contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
                && !LooksLikeHtmlDocument(body, contentType))
                return "text-plain";
            if (!contentType.Contains("html", StringComparison.OrdinalIgnoreCase)
                && !contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
                && !LooksLikeHtmlDocument(body, contentType))
                return "non-html";
        }
        else if (!LooksLikeHtmlDocument(body, contentType))
        {
            // No Content-Type and body is not an HTML document (raw downloads, API blobs).
            var trimmed = body.TrimStart();
            if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
                return "json";
            if (!trimmed.Contains('<'))
                return "non-html";
        }

        var idx = body.IndexOf(payload, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "unknown";

        var before = body[..idx];
        var lastTagOpen = before.LastIndexOf('<');
        var lastTagClose = before.LastIndexOf('>');

        if (lastTagOpen > lastTagClose)
        {
            var tagFragment = before[lastTagOpen..];
            if (tagFragment.Contains("script", StringComparison.OrdinalIgnoreCase))
                return IsInsideScriptStringLiteral(body, idx) ? "javascript-string" : "script";

            if (tagFragment.Contains('='))
            {
                if (EventHandlerAttr.IsMatch(tagFragment))
                    return "event-handler";
                if (UrlAttr.IsMatch(tagFragment))
                    return "url-attribute";

                var lastQuote = Math.Max(tagFragment.LastIndexOf('"'), tagFragment.LastIndexOf('\''));
                return lastQuote >= 0 ? "html-attribute-quoted" : "html-attribute-unquoted";
            }

            return "html-tag";
        }

        return "html-text";
    }

    /// <summary>True when the response looks like an HTML document (not a raw file/API blob).</summary>
    public static bool LooksLikeHtmlDocument(string? body, string? contentType)
    {
        if (!string.IsNullOrWhiteSpace(contentType)
            && contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.IsNullOrEmpty(body)) return false;
        var sample = body.Length > 4096 ? body[..4096] : body;
        return sample.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<html", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<head", StringComparison.OrdinalIgnoreCase)
               || sample.Contains("<body", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsReflectionDangerous(string payload, string context, bool encoded)
    {
        if (encoded) return false;

        // Raw API / download responses are not HTML document XSS without a document context.
        if (context is "json" or "text-plain" or "non-html")
            return false;

        if (context is "javascript-string" or "script-data")
        {
            if (payload.Contains("</script", StringComparison.OrdinalIgnoreCase))
                return true;
            return PayloadIntroducesEventHandler(payload) || HtmlMarkup.IsMatch(payload);
        }

        // Attribute breakout / injected handlers (e.g. src=x onerror=alert(1)) — dangerous in tag contexts.
        // Also dangerous when the payload itself is markup injected into the HTML body (html-text / html-markup):
        // early-return must NOT exclude those contexts — otherwise <img onerror=…> is marked safe.
        if (PayloadIntroducesEventHandler(payload) || PayloadBreaksQuotedAttribute(payload))
        {
            if (context is "url-attribute" or "html-attribute-quoted" or "html-attribute-unquoted"
                or "event-handler" or "html-tag" or "html-attribute" or "html-markup")
                return true;
            if (context is "html-text" && HtmlMarkup.IsMatch(payload))
                return true;
        }

        if (IsJavascriptUriPayload(payload) || IsDataUriPayload(payload))
            return context is "url-attribute" or "event-handler";

        return context switch
        {
            "script" or "event-handler" or "html-attribute-unquoted" or "html-markup" => true,
            "url-attribute" => IsJavascriptUriPayload(payload) || IsDataUriPayload(payload),
            "html-text" => HtmlMarkup.IsMatch(payload),
            "html-attribute" or "html-attribute-quoted" => false,
            "json" or "text-plain" or "non-html" => false,
            _ => false
        };
    }

    /// <summary>Payload itself introduces an event-handler attribute (onerror=, onload=, …).</summary>
    public static bool PayloadIntroducesEventHandler(string payload) =>
        !string.IsNullOrEmpty(payload) && EventHandlerAttr.IsMatch(payload);

    /// <summary>Payload looks like a quoted-attribute breakout (<c>"</c>, <c>'</c>, or <c>&gt;</c>).</summary>
    public static bool PayloadBreaksQuotedAttribute(string payload) =>
        !string.IsNullOrEmpty(payload)
        && (payload.Contains('"') || payload.Contains('\'') || payload.Contains('>'));

    public static ReflectionAnalysis AnalyzeReflection(string body, string originalPayload, string matchedVariant, bool encoded, string? contentType)
    {
        // Non-HTML responses (raw file downloads, JSON APIs) must not become high XSS without document context.
        if (!LooksLikeHtmlDocument(body, contentType)
            && (string.IsNullOrWhiteSpace(contentType)
                || !contentType.Contains("html", StringComparison.OrdinalIgnoreCase)))
        {
            var nonHtmlContext = DetermineReflectionContext(body, matchedVariant, contentType);
            if (nonHtmlContext is "json" or "text-plain" or "non-html")
            {
                var idxNh = body.IndexOf(matchedVariant, StringComparison.OrdinalIgnoreCase);
                var startNh = Math.Max(0, idxNh < 0 ? 0 : idxNh - 30);
                var endNh = Math.Min(body.Length, (idxNh < 0 ? 0 : idxNh) + matchedVariant.Length + 30);
                return new ReflectionAnalysis(
                    nonHtmlContext,
                    encoded,
                    Dangerous: false,
                    Reason: "Reflection in non-HTML response — not DOM/reflected XSS without HTML document context or sink+effect proof.",
                    Surrounding: "..." + body[startNh..endNh] + "...");
            }
        }

        var context = DetermineReflectionContext(body, matchedVariant, contentType);

        // Unencoded HTML markup reflected where a text node would be is a tag-injection /
        // breakout context — not "safe html-text". Reclassify before danger evaluation.
        if (!encoded && context == "html-text"
            && (HtmlMarkup.IsMatch(matchedVariant) || HtmlMarkup.IsMatch(originalPayload)))
        {
            context = "html-markup";
        }

        var dangerous = IsReflectionDangerous(originalPayload, context, encoded);

        var idx = body.IndexOf(matchedVariant, StringComparison.OrdinalIgnoreCase);
        var surroundingStart = Math.Max(0, idx - 30);
        var surroundingEnd = Math.Min(body.Length, idx + matchedVariant.Length + 30);
        var surrounding = "..." + body[surroundingStart..surroundingEnd] + "...";

        // Surrounding text may show a handler that the payload introduced even when context
        // was initially classified as a URL attribute.
        if (!dangerous && !encoded && idx >= 0
            && context is "url-attribute" or "html-attribute-quoted" or "html-attribute-unquoted" or "html-markup"
            && EventHandlerAttr.IsMatch(surrounding)
            && (PayloadIntroducesEventHandler(originalPayload) || PayloadBreaksQuotedAttribute(originalPayload)
                || PayloadIntroducesEventHandler(matchedVariant)))
        {
            dangerous = true;
            context = "event-handler";
        }

        // Surrounding HTML already shows the payload as a live tag with an event handler.
        if (!dangerous && !encoded && idx >= 0
            && EventHandlerAttr.IsMatch(surrounding)
            && (HtmlMarkup.IsMatch(originalPayload) || HtmlMarkup.IsMatch(matchedVariant)))
        {
            dangerous = true;
            context = "event-handler";
        }

        string? reason = null;
        if (dangerous)
        {
            reason = context switch
            {
                "url-attribute" when IsJavascriptUriPayload(originalPayload) =>
                    "Unencoded javascript: URI in URL attribute — may execute on navigation.",
                "event-handler" when PayloadIntroducesEventHandler(originalPayload)
                    || PayloadIntroducesEventHandler(matchedVariant) =>
                    "Payload introduces an event-handler attribute inside a tag — browser may execute it.",
                "html-markup" =>
                    "Unencoded HTML markup reflected into the document body — browser may parse tags/handlers as active content.",
                "html-text" =>
                    "Unencoded HTML/script markup in text content — browser may parse as active content.",
                _ => $"Unencoded payload in {context} context — browser may parse as active content."
            };
        }
        else if (encoded)
        {
            reason = matchedVariant.Contains("&lt;", StringComparison.Ordinal)
                ? "Payload was HTML-encoded — safe in this context."
                : "Payload was URL-encoded — safe in this context.";
        }
        else if (IsJavascriptUriPayload(originalPayload) && context is "html-text" or "json")
        {
            reason = "javascript: URI reflected in text content — not executable without a clickable URL attribute.";
        }

        return new ReflectionAnalysis(context, encoded, dangerous, reason, surrounding);
    }

    /// <summary>
    /// High-specificity markers for live DOM scanning — excludes generic substrings like "&lt;script"
    /// that appear on every HTML page and cause false positives.
    /// </summary>
    /// <remarks>
    /// Deliberately omits bare <c>alert(…)</c> calls: those collide with residual handlers from prior
    /// probes (stored XSS leftovers) and ambient page chrome. Prefer the full payload and event-handler
    /// attribute fragments so Dom.Dangerous requires same-probe causality.
    /// </remarks>
    public static List<string> BuildDomMarkers(string payload)
    {
        var markers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (payload.Length >= 6)
            markers.Add(payload);

        // Event-handler attribute fragments (quoted and unquoted) — include the handler *value*
        // so live-DOM checks against attr.value can match (e.g. window.__xss_proof=1).
        foreach (Match m in Regex.Matches(payload, @"on\w+\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase))
        {
            if (m.Value.Length >= 8)
                markers.Add(m.Value);
            if (m.Groups[1].Success && m.Groups[1].Value.Length >= 4)
                markers.Add(m.Groups[1].Value);
        }

        foreach (Match m in Regex.Matches(payload, @"on\w+\s*=\s*[^>\s""']+", RegexOptions.IgnoreCase))
        {
            if (m.Value.Length >= 8)
                markers.Add(m.Value);
        }

        foreach (Match m in AlertCall.Matches(payload))
        {
            if (m.Value.Length >= 4)
                markers.Add(m.Value);
        }

        // Inline <script> bodies become textContent after parse. Prefer distinctive inners
        // (length ≥ 12) so ambient alert(1) leftovers do not mark Dom.Dangerous.
        // AnalyzeDom also matches script.outerHTML against the full payload marker.
        foreach (Match m in Regex.Matches(
                     payload,
                     @"<\s*script\b[^>]*>([\s\S]*?)</\s*script\s*>",
                     RegexOptions.IgnoreCase))
        {
            var inner = m.Groups[1].Value.Trim();
            if (inner.Length >= 12)
                markers.Add(inner);
        }

        // Distinctive markup openers unique enough to avoid ambient false positives
        foreach (Match m in Regex.Matches(payload, @"<\s*(?:svg|img|iframe|script|body|video|audio|math)[^>]{0,80}", RegexOptions.IgnoreCase))
        {
            if (m.Value.Length >= 8)
                markers.Add(m.Value);
        }

        var list = markers.Where(m => m.Length >= 6).ToList();
        // HTML-tag payloads: drop bare event-handler fragments (e.g. onerror=alert(1)) that still
        // match inside entity-encoded script strings (&lt;img ...&gt;) without executable markup.
        if (ContainsHtmlMarkup(payload))
            list = list.Where(m => m.Contains('<') || m.Contains('>')).ToList();
        return list;
    }

    /// <summary>
    /// True when HTML in the payload appears only as entities in <paramref name="text"/>
    /// (no raw angle brackets) — substring matches are not exploitable.
    /// </summary>
    public static bool PayloadHtmlIsEntityEncodedOnly(string payload, string text)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(payload))
            return false;
        if (!payload.Contains('<') && !payload.Contains('>'))
            return false;
        if (text.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return false;
        if (text.Contains('<') || text.Contains('>'))
            return false;
        return text.Contains("&lt;", StringComparison.OrdinalIgnoreCase)
               || text.Contains("&gt;", StringComparison.OrdinalIgnoreCase)
               || text.Contains("&#", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Sink/DOM text contains an executable form of the payload (raw bytes), not entity-encoded HTML only.
    /// </summary>
    public static bool SinkOrDomTextContainsExecutablePayload(string payload, string text)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(payload))
            return false;
        if (text.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return true;
        if (PayloadHtmlIsEntityEncodedOnly(payload, text))
            return false;
        foreach (var marker in BuildDomMarkers(payload))
        {
            if (!text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                continue;
            if ((marker.Contains('<') || marker.Contains('>')) && !text.Contains('<') && !text.Contains('>'))
                continue;
            if (ContainsHtmlMarkup(payload) && !marker.Contains('<') && !marker.Contains('>'))
                continue;
            return true;
        }
        return false;
    }

    /// <summary>
    /// True when Dom.Dangerous is backed by strong payload markers (see <see cref="BuildDomMarkers"/>)
    /// and the payload appears to have rendered — not a residual/ambient false positive.
    /// </summary>
    public static bool DomEvidenceIsPayloadCausal(string payload, InputTraceResult.DomTrace? dom)
    {
        if (dom is not { Dangerous: true, PayloadRendered: true })
            return false;
        if (string.IsNullOrEmpty(payload) || payload.Length < 6)
            return false;

        // Strong markers only (full payload / event-handler attrs / distinctive tags).
        // If none exist for this payload, Dangerous cannot be causal.
        return BuildDomMarkers(payload).Count > 0;
    }

    /// <summary>
    /// Classic &lt;script&gt; elements inserted via innerHTML are inert — browsers do not execute them.
    /// </summary>
    public static bool IsInertInnerHtmlScriptDomEvidence(
        string payload,
        InputTraceResult.DomTrace? dom,
        InputTraceResult.SinkTrace? sinks)
    {
        if (dom is not { Dangerous: true, PayloadRendered: true })
            return false;
        if (sinks is { ExecutionConfirmed: true })
            return false;
        if (!payload.Contains("<script", StringComparison.OrdinalIgnoreCase))
            return false;
        if (PayloadIntroducesEventHandler(payload))
            return false;

        var ctx = dom.Context ?? "";
        return ctx.Contains("script-content", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Distinctive substrings to locate payloads in HTTP response bodies (reflection analysis).
    /// </summary>
    public static List<string> BuildPayloadMarkers(string payload)
    {
        var markers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { payload };

        var alertMatch = AlertCall.Match(payload);
        if (alertMatch.Success)
            markers.Add(alertMatch.Value);

        foreach (Match m in EventHandlerName.Matches(payload))
            markers.Add(m.Value);

        foreach (var fragment in new[] { "onerror", "onload", "onclick", "onmouseover" })
        {
            if (payload.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                markers.Add(fragment);
        }

        return markers.ToList();
    }

    public static IEnumerable<string> GetPayloadReflectionVariants(string payload)
    {
        yield return payload;
        yield return HttpUtility.HtmlEncode(payload);
        yield return HttpUtility.UrlEncode(payload);
        yield return payload.Replace("<", "&lt;").Replace(">", "&gt;");
    }

    /// <summary>
    /// Optional note for fuzzer reflection flags — helps prioritize non-exploitable echoes.
    /// </summary>
    public static string? GetFuzzerReflectionContextNote(string payload, string body)
    {
        if (payload.Length < 4 || !body.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return null;

        var context = DetermineReflectionContext(body, payload, null);
        if (IsJavascriptUriPayload(payload) && context is "html-text" or "json")
        {
            return "Reflected in text content (not URL attribute) — javascript: URI unlikely to execute";
        }

        if (context is "html-attribute-quoted" or "json")
        {
            return $"Reflected in {context} context — verify whether encoding prevents exploitation";
        }

        return null;
    }

    /// <summary>
    /// When DOM confirms safe text-node rendering, downgrade server-side false positives.
    /// DOM execution context is authoritative over raw response-body substring matching.
    /// </summary>
    public static bool ShouldDowngradeServerDanger(
        string payload,
        IReadOnlyList<InputTraceResult.ReflectionInfo> reflections,
        InputTraceResult.DomTrace? dom)
    {
        if (dom is not { Dangerous: false, PayloadRendered: true })
            return false;

        if (!reflections.Any(r => r.Dangerous))
            return false;

        var domContext = dom.Context ?? "";
        var textNodeOnly = domContext.Contains("text-node", StringComparison.OrdinalIgnoreCase)
                           && !domContext.Contains("event-handler", StringComparison.OrdinalIgnoreCase)
                           && !domContext.Contains("script", StringComparison.OrdinalIgnoreCase)
                           && !domContext.Contains("html-parsed", StringComparison.OrdinalIgnoreCase)
                           && !domContext.Contains("url-attribute", StringComparison.OrdinalIgnoreCase);

        if (!textNodeOnly)
            return false;

        // javascript:/data: echoed as plain text — never executable without a URL attribute
        if ((IsJavascriptUriPayload(payload) || IsDataUriPayload(payload)) && !HtmlMarkup.IsMatch(payload))
            return true;

        // HTML-like strings displayed inside text nodes (e.g. <pre>) were not parsed as markup.
        // Do not downgrade html-markup / event-handler reflections — those are tag-injection contexts.
        if (HtmlMarkup.IsMatch(payload)
            && reflections.All(r => r.Context is "html-text" or "json")
            && !PayloadIntroducesEventHandler(payload))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// When DOM confirms safe rendering but sink hooks fired, downgrade if payload only reached the sink
    /// as browser URL-encoded HTML (e.g. %3C, %3E) — the dangerous path exists but is neutralized.
    /// </summary>
    public static bool IsSinkPayloadUrlEncodedNeutralized(
        InputTraceResult.SinkTrace? sinks,
        InputTraceResult.DomTrace? dom)
    {
        if (dom is { Dangerous: true }) return false;
        if (sinks is not { PayloadReachedSink: true }) return false;

        var payloadHits = sinks.Hits
            .Where(h => h.ContainsPayload && !string.IsNullOrEmpty(h.Snippet))
            .ToList();
        if (payloadHits.Count == 0) return false;

        return payloadHits.All(h => ContainsUrlEncodedHtmlMarkers(h.Snippet!));
    }

    /// <summary>
    /// Sink hooks can fire for textContent / safe attribute writes that still contain the payload.
    /// Treat as non-exploitable when DOM reports safe context and sink snippets lack executable markup.
    /// </summary>
    public static bool IsSinkReachSafeDespiteDom(
        string payload,
        InputTraceResult.SinkTrace? sinks,
        InputTraceResult.DomTrace? dom)
    {
        if (sinks is not { PayloadReachedSink: true }) return false;
        if (dom is { Dangerous: true }) return false;

        // Explicit safe-context DOM evidence contradicts CRITICAL sink claims.
        if (dom is { Dangerous: false, PayloadRendered: true }
            || (dom?.Reason?.Contains("safe context", StringComparison.OrdinalIgnoreCase) == true))
        {
            if (IsSinkPayloadUrlEncodedNeutralized(sinks, dom))
                return true;
            return !SinkSnippetLooksExecutable(sinks, payload);
        }

        return IsSinkPayloadUrlEncodedNeutralized(sinks, dom);
    }

    public static bool SinkSnippetLooksExecutable(InputTraceResult.SinkTrace sinks, string payload)
    {
        foreach (var hit in sinks.Hits.Where(h => h.ContainsPayload && !string.IsNullOrEmpty(h.Snippet)))
        {
            if (SinkOrDomTextContainsExecutablePayload(payload, hit.Snippet!))
                return true;
        }

        return false;
    }

    private static bool ContainsUrlEncodedHtmlMarkers(string snippet) =>
        snippet.Contains("%3C", StringComparison.OrdinalIgnoreCase)
        || snippet.Contains("%3E", StringComparison.OrdinalIgnoreCase)
        || snippet.Contains("&lt;", StringComparison.OrdinalIgnoreCase)
        || snippet.Contains("&gt;", StringComparison.OrdinalIgnoreCase)
        || snippet.Contains("&#60;", StringComparison.OrdinalIgnoreCase)
        || snippet.Contains("&#62;", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// All payload hits are echoes of the full document URL (Angular location.href attributes, etc.).
    /// </summary>
    public static bool SinkHitsAreDocumentUrlEchoOnly(
        string payload,
        string? documentUrl,
        IEnumerable<InputTraceResult.SinkHit> hits)
    {
        if (string.IsNullOrWhiteSpace(documentUrl))
            return false;

        var payloadHits = hits.Where(h => h.ContainsPayload).ToList();
        if (payloadHits.Count == 0)
            return false;

        return payloadHits.All(h =>
            SnippetIsDocumentUrlEcho(payload, documentUrl, h.Snippet)
            || SinkHitIsInertSelfReferentialPageUrl(h.Sink, h.Snippet, documentUrl, payload));
    }

    /// <summary>
    /// Sink argument is the current page URL (or resolves to it) — payload appears only because it is in location.href.
    /// Covers copy-link / retry patterns: a.href = location.href, fetch(currentUrl), etc. Fragments are not executed there.
    /// </summary>
    public static bool SinkHitIsInertSelfReferentialPageUrl(
        string? sink,
        string? snippet,
        string? documentUrl,
        string payload)
    {
        if (string.IsNullOrWhiteSpace(documentUrl) || string.IsNullOrWhiteSpace(snippet))
            return false;

        var s = sink ?? "";
        if (s is not ("a.href" or "area.href" or "fetch" or "xhr.open" or "XMLHttpRequest.open"
            or "location.assign" or "location.replace" or "location.href" or "window.open"
            or "form.action" or "button.formAction" or "input.formAction"))
            return false;

        if (!PayloadAppearsInDocumentUrl(payload, documentUrl))
            return false;

        return SnippetIsDocumentUrlEcho(payload, documentUrl, snippet)
               || UrlSnippetResolvesToSameDocument(snippet.Trim(), documentUrl.Trim());
    }

    public static bool SnippetIsDocumentUrlEcho(string payload, string documentUrl, string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet) || string.IsNullOrWhiteSpace(documentUrl))
            return false;

        var sn = snippet.Trim();
        var doc = documentUrl.Trim();

        if (string.Equals(sn, doc, StringComparison.OrdinalIgnoreCase))
            return PayloadAppearsInDocumentUrl(payload, doc);

        if (UrlsRepresentSameDocument(sn, doc))
            return PayloadAppearsInDocumentUrl(payload, doc);

        if (UrlSnippetResolvesToSameDocument(sn, doc))
            return PayloadAppearsInDocumentUrl(payload, doc);

        if (sn.Length >= doc.Length - 8
            && PayloadAppearsInDocumentUrl(payload, doc)
            && (sn.Contains(doc, StringComparison.OrdinalIgnoreCase)
                || doc.Contains(sn, StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private static bool PayloadAppearsInDocumentUrl(string payload, string documentUrl)
    {
        if (string.IsNullOrEmpty(payload))
            return true;
        if (documentUrl.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return true;

        var dataEncoded = Uri.EscapeDataString(payload);
        if (!string.Equals(dataEncoded, payload, StringComparison.Ordinal)
            && documentUrl.Contains(dataEncoded, StringComparison.OrdinalIgnoreCase))
            return true;

        var formEncoded = HttpUtility.UrlEncode(payload);
        if (!string.IsNullOrEmpty(formEncoded)
            && !string.Equals(formEncoded, payload, StringComparison.Ordinal)
            && documentUrl.Contains(formEncoded, StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private static bool UrlSnippetResolvesToSameDocument(string snippet, string documentUrl)
    {
        if (UrlsRepresentSameDocument(snippet, documentUrl))
            return true;

        if (!Uri.TryCreate(documentUrl, UriKind.Absolute, out var baseUri))
            return false;

        if (Uri.TryCreate(baseUri, snippet, out var resolved))
            return UrlsRepresentSameDocument(resolved.ToString(), documentUrl);

        return false;
    }

    private static bool UrlsRepresentSameDocument(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua)
            || !Uri.TryCreate(b, UriKind.Absolute, out var ub))
            return false;

        return string.Equals(ua.Scheme, ub.Scheme, StringComparison.OrdinalIgnoreCase)
               && string.Equals(ua.Host, ub.Host, StringComparison.OrdinalIgnoreCase)
               && ua.Port == ub.Port
               && string.Equals(ua.AbsolutePath, ub.AbsolutePath, StringComparison.OrdinalIgnoreCase)
               && string.Equals(ua.Query, ub.Query, StringComparison.OrdinalIgnoreCase)
               && string.Equals(NormalizeUrlFragment(ua.Fragment), NormalizeUrlFragment(ub.Fragment),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeUrlFragment(string fragment)
    {
        if (string.IsNullOrEmpty(fragment))
            return "";
        var f = fragment.StartsWith('#') ? fragment[1..] : fragment;
        try { return Uri.UnescapeDataString(f.Replace('+', ' ')); }
        catch { return f; }
    }

    /// <summary>Nav highlight scripts that match the current page URL in an anchor href selector (benign reach noise).</summary>
    public static bool IsNavActiveLinkEcho(string? snippet, string? documentUrl, string? canaryOrPayload)
    {
        if (string.IsNullOrWhiteSpace(snippet) || string.IsNullOrWhiteSpace(documentUrl))
            return false;
        var sn = snippet;
        if (!sn.Contains("href", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!sn.Contains(documentUrl, StringComparison.OrdinalIgnoreCase)
            && (canaryOrPayload == null || !sn.Contains(canaryOrPayload, StringComparison.OrdinalIgnoreCase)))
            return false;
        return sn.Contains("nav", StringComparison.OrdinalIgnoreCase)
               || sn.Contains("location.href", StringComparison.OrdinalIgnoreCase)
               || sn.Contains("querySelector", StringComparison.OrdinalIgnoreCase)
               || sn.Contains("[href=", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Payload reached eval/Function as data inside JS string literals only (no quote breakout).
    /// </summary>
    public static bool IsPayloadOnlyInJsStringLiteral(string? sinkName, string? snippet, string payload)
    {
        if (string.IsNullOrWhiteSpace(snippet) || string.IsNullOrWhiteSpace(payload))
            return false;
        if (sinkName is not ("eval" or "Function" or "Function.constructor" or "setTimeout(string)" or "setInterval(string)"))
            return false;

        var idx = snippet.IndexOf(payload, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return false;

        var beforePayload = snippet[..idx];
        if (beforePayload.Contains("\";") || beforePayload.Contains("';")
            || beforePayload.Contains("\"+") || beforePayload.Contains("'+")
            || beforePayload.Contains("\\\";") || beforePayload.Contains("\\';"))
            return false;

        var openQuote = idx > 0 ? snippet[idx - 1] : '\0';
        if (openQuote is not '"' and not '\'')
            return false;

        var afterIdx = idx + payload.Length;
        if (afterIdx >= snippet.Length)
            return true;

        var close = snippet[afterIdx];
        return close is '"' or '\'' or ';' or ')' or ',' or ' ';
    }

    /// <summary>
    /// Payload substring appears in an HTML sink but only inside a URL attribute value (no tag/event breakout).
    /// </summary>
    public static bool IsPayloadTrappedInNonExecutableHtmlSink(string payload, string sink, string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet)
            || string.IsNullOrWhiteSpace(payload)
            || !snippet.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return false;

        if (payload.Contains('<') || PayloadIntroducesEventHandler(payload))
            return false;

        if (sink is not ("document.write" or "document.writeln" or "innerHTML" or "outerHTML"
            or "insertAdjacentHTML" or "createContextualFragment" or "setHTMLUnsafe"
            or "shadowRoot.innerHTML" or "jquery.html" or "jquery.append"))
            return false;

        if (Regex.IsMatch(snippet, @"on\w+\s*=\s*[""'][^""']*"
                              + Regex.Escape(payload)
                              + @"[^""']*[""']", RegexOptions.IgnoreCase))
            return false;

        var tagMatch = Regex.Match(
            snippet,
            @"<img\b[^>]*>",
            RegexOptions.IgnoreCase);
        if (!tagMatch.Success)
            return false;

        var tag = tagMatch.Value;
        if (Regex.IsMatch(tag, @"on\w+\s*=", RegexOptions.IgnoreCase))
            return false;

        return Regex.IsMatch(
            tag,
            @"\bsrc\s*=\s*[""'][^""']*"
            + Regex.Escape(payload)
            + @"[^""']*[""']",
            RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// True when every payload-bearing sink hit is non-executable (trapped URL text or benign URL attribute).
    /// </summary>
    public static bool SinkHitsLackExecutablePayloadContext(string payload, InputTraceResult.SinkTrace sinks)
    {
        var hits = sinks.Hits.Where(h => h.ContainsPayload).ToList();
        if (hits.Count == 0)
            return false;

        return hits.All(h =>
            IsPayloadTrappedInNonExecutableHtmlSink(payload, h.Sink, h.Snippet)
            || IsBenignAbsoluteUrlAttributeWrite(h.Sink, h.Snippet, payload)
            || IsBenignHttpApiQuerySink(h.Sink, h.Snippet, payload)
            || SnippetUsesNonFiringEventHandler(payload, h.Snippet));
    }

    /// <summary>Event handler on an element that will not fire (e.g. onload on anchor).</summary>
    public static bool SnippetUsesNonFiringEventHandler(string payload, string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet) || !PayloadIntroducesEventHandler(payload))
            return false;

        if (!Regex.IsMatch(snippet, @"<(a|area|link|base|meta)\b", RegexOptions.IgnoreCase))
            return false;

        return Regex.IsMatch(snippet, @"\bonload\s*=", RegexOptions.IgnoreCase);
    }

    private static bool IsInsideScriptStringLiteral(string body, int payloadIndex)
    {
        var scriptOpen = body.LastIndexOf("<script", payloadIndex, StringComparison.OrdinalIgnoreCase);
        if (scriptOpen < 0) return false;
        var scriptClose = body.IndexOf("</script", scriptOpen, StringComparison.OrdinalIgnoreCase);
        if (scriptClose >= 0 && payloadIndex > scriptClose)
            return false;

        var segment = body[scriptOpen..payloadIndex];
        var inSingle = false;
        var inDouble = false;
        for (var i = 0; i < segment.Length; i++)
        {
            var c = segment[i];
            if (c == '\\' && i + 1 < segment.Length)
            {
                i++;
                continue;
            }

            if (c == '\'' && !inDouble) inSingle = !inSingle;
            else if (c == '"' && !inSingle) inDouble = !inDouble;
        }

        return inSingle || inDouble;
    }

    /// <summary>Form/search flows that pass typed text into fetch/xhr query parameters (not HTML/DOM XSS).</summary>
    public static bool IsBenignHttpApiQuerySink(string? sinkName, string? snippet, string payload)
    {
        if (string.IsNullOrWhiteSpace(snippet) || string.IsNullOrWhiteSpace(payload))
            return false;
        if (sinkName is not ("fetch" or "xhr.open" or "xhr.send" or "XMLHttpRequest.open"))
            return false;
        if (!snippet.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return false;
        if (ContainsHtmlMarkup(payload) || PayloadIntroducesEventHandler(payload))
            return false;
        if (IsJavascriptUriPayload(payload) || IsDataUriPayload(payload))
            return false;

        var escaped = Uri.EscapeDataString(payload);
        return Regex.IsMatch(snippet, @"[?&][^=&\s]+=" + Regex.Escape(payload), RegexOptions.IgnoreCase)
               || (!string.Equals(escaped, payload, StringComparison.Ordinal)
                   && Regex.IsMatch(snippet, @"[?&][^=&\s]+=" + Regex.Escape(escaped), RegexOptions.IgnoreCase));
    }

    public static bool SinkHitsAreBenignSearchOrApiOnly(string payload, InputTraceResult.SinkTrace sinks)
    {
        var hits = sinks.Hits.Where(h => h.ContainsPayload).ToList();
        if (hits.Count == 0)
            return false;
        return hits.All(h => IsBenignHttpApiQuerySink(h.Sink, h.Snippet, payload));
    }

    /// <summary>setAttribute wrote an absolute http(s) URL without javascript: or event-handler markup.</summary>
    public static bool IsBenignAbsoluteUrlAttributeWrite(string sink, string? snippet, string payload)
    {
        if (sink is not ("setAttribute" or "setAttributeNS" or "Attr.value"))
            return false;
        if (string.IsNullOrWhiteSpace(snippet))
            return false;

        var sn = snippet.Trim();
        if (!Uri.TryCreate(sn, UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme is not ("http" or "https"))
            return false;
        if (sn.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
            return false;
        if (Regex.IsMatch(sn, @"on\w+\s*=", RegexOptions.IgnoreCase))
            return false;

        return sn.Contains(payload, StringComparison.OrdinalIgnoreCase);
    }
}
