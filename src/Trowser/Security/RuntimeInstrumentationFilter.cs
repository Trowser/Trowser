using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Drop WebView2 host-bridge and Trowser sensor listeners from client-side attack-surface scoring.
/// </summary>
public static class RuntimeInstrumentationFilter
{
    public static bool IsSanitizerSink(string? sinkName) =>
        !string.IsNullOrEmpty(sinkName)
        && sinkName.Contains("DOMPurify", StringComparison.OrdinalIgnoreCase);

    public static bool IsToolArtifactSink(string? sinkName, string? stackTrace, string? sampleData)
    {
        var stack = stackTrace ?? "";
        var data = sampleData ?? "";
        if (IsSanitizerSink(sinkName))
            return false;

        if (SinkStackAnalyzer.IsSensorOrHostOnlyStack(stack))
            return true;

        if (data.Contains("MathJax.version", StringComparison.OrdinalIgnoreCase)
            || data.Contains("pendo.VERSION", StringComparison.OrdinalIgnoreCase)
            || data.Contains("$.ua.version", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(sinkName, "Function", StringComparison.OrdinalIgnoreCase)
            && stack.Length < 12)
            return true;

        if (IsBrowserChromeErrorPageSample(data))
            return true;

        return false;
    }

    /// <summary>WebView2/Chromium network-error or blocked-content interstitial (not the app under test).</summary>
    public static bool IsBrowserChromeErrorPageSample(string? sampleData)
    {
        if (string.IsNullOrWhiteSpace(sampleData))
            return false;

        var s = sampleData;
        if (s.Contains("chrome-error://", StringComparison.OrdinalIgnoreCase)
            || s.Contains("edge-error://", StringComparison.OrdinalIgnoreCase)
            || s.Contains("ERR_BLOCKED", StringComparison.OrdinalIgnoreCase)
            || s.Contains("is blocked", StringComparison.OrdinalIgnoreCase)
            || s.Contains("blocked by", StringComparison.OrdinalIgnoreCase))
            return true;

        if (s.Contains("Det här innehållet är blockerat", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Kontakta webbplatsens ägare", StringComparison.OrdinalIgnoreCase)
            || s.Contains("blockerad", StringComparison.OrdinalIgnoreCase)
            || s.Contains("This content is blocked", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Contact the site owner", StringComparison.OrdinalIgnoreCase))
            return true;

        return s.Contains("evil.trowser.test", StringComparison.OrdinalIgnoreCase)
               && (s.Contains("blocker", StringComparison.OrdinalIgnoreCase)
                   || s.Contains("blockerad", StringComparison.OrdinalIgnoreCase)
                   || s.Contains("blocked", StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsClickjackProbeIframe(string? src) =>
        !string.IsNullOrEmpty(src)
        && src.Contains("data:text/html", StringComparison.OrdinalIgnoreCase);

    public static bool IsHostOrSensorListener(string? stackTrace, string? handlerPreview)
    {
        var stack = stackTrace ?? "";
        var preview = handlerPreview ?? "";
        if (stack.Contains("createChromeWebView", StringComparison.OrdinalIgnoreCase))
            return true;
        if (preview.Contains("evil.trowser.test", StringComparison.OrdinalIgnoreCase))
            return true;
        if (preview.Contains("noteSource('postMessage'", StringComparison.OrdinalIgnoreCase)
            || preview.Contains("noteSource(\"postMessage\"", StringComparison.OrdinalIgnoreCase))
            return true;
        if (stack.Contains("__trowser", StringComparison.OrdinalIgnoreCase)
            && stack.Contains("postMessage", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static bool IsGadgetRadarArtifact(string? stackTrace, string? data)
    {
        if (SinkStackAnalyzer.IsSensorOrHostOnlyStack(stackTrace))
            return true;
        if (data?.Contains("(count)", StringComparison.Ordinal) == true)
            return false;
        return false;
    }
}
