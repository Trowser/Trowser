namespace Trowser.Automation;

/// <summary>
/// In-memory network body capture limits (WebView2 response stream read cap).
/// </summary>
public static class NetworkCaptureLimits
{
    public const int MaxTextBodyChars = 102400;

    /// <summary>
    /// Event-stream responses (native SSE, live <c>fetch()</c> polls, breakpoint captures).
    /// Kept high for security-test transparency; general text bodies stay at <see cref="MaxTextBodyChars"/>.
    /// </summary>
    public const int MaxEventStreamBodyChars = 4_194_304;

    public static int BodyCaptureLimit(NetworkEntry entry) =>
        entry.IsEventStream ? MaxEventStreamBodyChars : MaxTextBodyChars;

    /// <summary>
    /// Text-like responses worth keeping in the log. Script and stylesheet are included so a missing
    /// or unusual Content-Type (for example <c>env.js</c> or <c>application/ecmascript</c>) still captures a body.
    /// Images, fonts, and other binary types stay out.
    /// </summary>
    public static bool ShouldCaptureResponseBody(string? resourceType, string? contentType)
    {
        if (resourceType is "Fetch" or "Document" or "XHR" or "Script" or "Stylesheet")
            return true;
        if (string.IsNullOrEmpty(contentType))
            return false;
        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("html", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("text/yaml", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("application/yaml", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("application/x-yaml", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("text/markdown", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("ecmascript", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("text/css", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// WebView2 omits some request headers (and deliberately hides Cookie). CDP's view can fill the gaps.
    /// Cookie is not copied back — that strip is intentional.
    /// </summary>
    public static bool ShouldMergeCapturedRequestHeader(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith(":", StringComparison.Ordinal))
            return false;
        return !name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)
               && !name.Equals("Cookie2", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Headers present on the CDP request and absent from the WebView2 entry.</summary>
    public static Dictionary<string, string> MissingRequestHeaders(
        IReadOnlyDictionary<string, string> have,
        IReadOnlyDictionary<string, string> seen)
    {
        var missing = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in seen)
        {
            if (!ShouldMergeCapturedRequestHeader(kv.Key))
                continue;
            var exists = false;
            foreach (var key in have.Keys)
            {
                if (key.Equals(kv.Key, StringComparison.OrdinalIgnoreCase))
                {
                    exists = true;
                    break;
                }
            }
            if (!exists)
                missing[kv.Key] = kv.Value;
        }
        return missing;
    }

    public static void MergeMissingRequestHeaders(
        Dictionary<string, string> target,
        IReadOnlyDictionary<string, string>? extras)
    {
        if (extras == null || extras.Count == 0)
            return;
        foreach (var kv in MissingRequestHeaders(target, extras))
            target[kv.Key] = kv.Value;
    }

    /// <summary>True when the in-memory capture hit the hard character cap (large bundles).</summary>
    public static bool? IsResponseBodyTruncated(NetworkEntry entry)
    {
        if (entry.ResponseBody == null)
            return null;

        if (entry.ResponseBody.Length >= BodyCaptureLimit(entry))
            return true;

        if (IsRequestBodyTruncated(entry.ResponseBody))
            return true;

        return false;
    }

    /// <summary>
    /// Declared Content-Length exceeds captured text by more than a small tolerance (encoding/chunked quirks).
    /// Not the same as hitting <see cref="MaxTextBodyChars"/>.
    /// </summary>
    public static bool? IsResponseBodySizeMismatch(NetworkEntry entry)
    {
        if (entry.ResponseBody == null)
            return null;

        if (entry.ContentLengthBytes is not long declared || declared <= entry.ResponseBody.Length)
            return false;

        var gap = declared - entry.ResponseBody.Length;
        const long tolerance = 32;
        if (gap <= tolerance)
            return false;

        if (declared > 0 && gap * 100 / declared <= 1)
            return false;

        return true;
    }

    public static bool IsRequestBodyTruncated(string? requestBody) =>
        requestBody != null
        && requestBody.EndsWith("...(truncated)", StringComparison.Ordinal);

    public static string? SliceBody(string? body, int offset, int limit)
    {
        if (body == null || limit <= 0 || offset < 0 || offset >= body.Length)
            return offset >= body?.Length ? "" : null;
        var take = Math.Min(limit, body.Length - offset);
        return body.Substring(offset, take);
    }

    public static Dictionary<string, object?> ResponseBodyCaptureFields(NetworkEntry e) => new()
    {
        ["responseBodyCapturedChars"] = e.ResponseBody?.Length,
        ["contentLengthBytes"] = e.ContentLengthBytes,
        ["responseBodyTruncated"] = IsResponseBodyTruncated(e),
        ["responseBodySizeMismatch"] = IsResponseBodySizeMismatch(e),
        ["bodyCaptureLimitChars"] = BodyCaptureLimit(e),
        ["requestBodyTruncated"] = e.RequestBody != null && IsRequestBodyTruncated(e.RequestBody)
    };
}
