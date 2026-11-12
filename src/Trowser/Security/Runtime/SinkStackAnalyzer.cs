namespace Trowser.Security.Runtime;

/// <summary>
/// Separates page JavaScript frames from runtime-sensor hook frames in captured stacks.
/// </summary>
public static class SinkStackAnalyzer
{
    private static readonly string[] SensorMarkers =
    [
        "trowser-runtime-sensor",
        "captureSink",
        "captureSource",
        "captureListener",
        "pushHost",
        "__trowser_rt",
        "RuntimeSensorScript",
        "__trowser_rt_install",
        "installMissingGlobalRadar",
        "__trowser_gadget_proxy",
        "logRead"
    ];

    /// <summary>Stack lines attributable to the instrumented page (not the sensor IIFE).</summary>
    public static string GetPageStack(string? stackTrace)
    {
        if (string.IsNullOrWhiteSpace(stackTrace)) return "";

        var lines = stackTrace.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var page = new List<string>();
        foreach (var line in lines)
        {
            if (IsSensorFrameLine(line)) continue;
            page.Add(line);
        }

        return string.Join("\n", page.Take(10));
    }

    public static bool HasPageFrame(string? stackTrace) =>
        !string.IsNullOrWhiteSpace(GetPageStack(stackTrace));

    internal static bool IsSensorFrameLine(string line)
    {
        foreach (var m in SensorMarkers)
        {
            if (line.Contains(m, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // CDP / WebView evaluate wrapper without page attribution
        if (line.Contains("at <anonymous>", StringComparison.Ordinal)
            && line.Contains("evaluate", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    /// <summary>True when the event should be dropped as sensor/host noise (no page frame).</summary>
    public static bool IsSensorOrHostOnlyStack(string? stackTrace)
    {
        var page = GetPageStack(stackTrace);
        if (string.IsNullOrWhiteSpace(page)) return true;
        if (page.Contains("tryFunc", StringComparison.OrdinalIgnoreCase)
            || page.Contains("runPass", StringComparison.OrdinalIgnoreCase)
            || page.Contains("createChromeWebView", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    /// <summary>True when a stack frame URL matches the page origin or a loaded script origin.</summary>
    public static bool IsFirstPartyStack(
        string? stackTrace,
        string? pageOrigin,
        IReadOnlyCollection<string>? scriptOrigins = null)
    {
        if (string.IsNullOrWhiteSpace(stackTrace))
            return false;

        foreach (var line in stackTrace.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IsSensorFrameLine(line))
                continue;
            if (!line.Contains("://", StringComparison.Ordinal))
                continue;

            var urlPart = ExtractUrlFromStackLine(line);
            if (string.IsNullOrEmpty(urlPart))
                continue;
            if (!Uri.TryCreate(urlPart, UriKind.Absolute, out var uri))
                continue;

            var origin = uri.GetLeftPart(UriPartial.Authority);
            if (!string.IsNullOrEmpty(pageOrigin)
                && origin.Equals(pageOrigin, StringComparison.OrdinalIgnoreCase))
                return true;

            if (scriptOrigins != null)
            {
                foreach (var o in scriptOrigins)
                {
                    if (origin.Equals(o, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }

        return false;
    }

    internal static string? ExtractUrlFromStackLine(string line)
    {
        var paren = line.IndexOf('(');
        if (paren >= 0)
        {
            var close = line.IndexOf(')', paren);
            var inner = close > paren ? line[(paren + 1)..close] : line[(paren + 1)..];
            var at = inner.LastIndexOf(" at ", StringComparison.Ordinal);
            if (at >= 0)
                inner = inner[(at + 4)..].Trim();
            var space = inner.IndexOf(' ');
            if (space > 0)
                inner = inner[..space];
            if (inner.Contains("://", StringComparison.Ordinal))
                return inner;
        }

        var http = line.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
        if (http < 0)
            http = line.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
        if (http < 0)
            return null;

        var rest = line[http..];
        var end = rest.IndexOfAny([' ', ')', '\t']);
        return end > 0 ? rest[..end] : rest;
    }
}
